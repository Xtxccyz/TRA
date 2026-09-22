"""Compatibility shim: this module MOVED to `threat_report_agent.investigation.investigation_protocol`.

Structural move only - no behaviour change. The shim rebinds `sys.modules` to the real module instead of
`import *`, so one module object serves both paths and PRIVATE names remain reachable, and patching either path
affects the other. Deleting this shim is plan step P4, in its own checkpoint.
"""
import sys as _sys

# `import <pkg>.<sub> as _real` rather than `from <pkg> import <sub> as _real`, and the difference MATTERS here:
# the import gate records BOTH `<pkg>.<sub>` and `<pkg>` for the `from` form, so the shim would depend on the
# `investigation` PACKAGE. Because `investigation.investigation` normalises onto the package node (the
# `public_path_unchanged` entry in `docs/import-policy.json`), that dependency closed a cycle with the
# implementation's own import of this module: `investigation <-> investigation_protocol`. The `import` form records
# only the submodule, which is the dependency this shim actually has. Runtime behaviour is identical: both forms
# import the parent package and bind the submodule object.
import threat_report_agent.investigation.investigation_protocol as _real

_sys.modules[__name__] = _real
