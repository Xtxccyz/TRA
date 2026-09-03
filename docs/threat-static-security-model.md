# Threat Static Security Model

The `threat-static` profile is a deny-by-default static analysis surface.
Only typed Threat tools are visible. Bash, PowerShell, terminal, arbitrary
code, filesystem execution, web fetch, and sample-specified network access are
absent from the model tool schema.

Sample bytes, strings, archive members, background text, and model output are
`UNTRUSTED_DATA`. They can be cited as Evidence but cannot alter policy,
permissions, task scope, or tool registration. Backend Policy, Action Catalog,
Temporal, and isolated static Workers remain the final authorization boundary.

The model gateway is single-routed: DSH adapter requests are forwarded to the
existing backend Model Gateway with case/task/session/turn/step metadata. Raw
requests and responses remain restricted audit assets; DSH session events only
retain bounded summaries and IDs.
