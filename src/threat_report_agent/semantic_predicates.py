"""Compatibility shim: this module MOVED to `threat_report_agent.investigation.semantic_predicates`.

Structural move only - no behaviour change. The shim rebinds `sys.modules` to the real module instead of
`import *`, so one module object serves both paths and PRIVATE names remain reachable, and patching either path
affects the other. Deleting this shim is plan step P4, in its own checkpoint.
"""
import sys as _sys

# `import <pkg>.<sub> as _real` rather than `from <pkg> import <sub> as _real`, for the reason measured at
# `investigation_protocol`, `behavior_catalog` and `mechanism_completeness`. MEASURED HERE AT ITS WIDEST: the `from`
# form records an edge to the `investigation` PACKAGE, and this module is imported by modules the package itself
# depends on (`facts.dataflow`, `facts.thread_start`, `static.static_analysis`, `static.pma_static_plan`), so that
# single edge closed a SEVEN-module cycle:
#   controlled_emulation <-> dataflow <-> emulation_plan <-> facts.thread_start <-> investigation <->
#   pma_static_plan <-> semantic_predicates <-> static_analysis
# The `import` form records only the submodule, which is the dependency this shim actually has. Runtime behaviour is
# identical: both forms import the parent package and bind the submodule object.
import threat_report_agent.investigation.semantic_predicates as _real

_sys.modules[__name__] = _real
