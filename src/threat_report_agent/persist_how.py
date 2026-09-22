"""Compatibility shim: this module MOVED to `threat_report_agent.investigation.persist_how`.

Structural move only - no behaviour change. The shim rebinds `sys.modules` to the real module instead of
`import *`, so one module object serves both paths and PRIVATE names remain reachable, and patching either path
affects the other. Deleting this shim is plan step P4, in its own checkpoint.
"""
import sys as _sys

from threat_report_agent.investigation import persist_how as _real

_sys.modules[__name__] = _real
