"""Compatibility shim: this module MOVED to `threat_report_agent.model.model_gateway`.

Structural move only - no behaviour change. The shim rebinds `sys.modules` to the real module instead of
`import *`, so one module object serves both paths and PRIVATE names remain reachable, and patching either path
affects the other. Deleting this shim is plan step P4, in its own checkpoint.
"""
import sys as _sys

from threat_report_agent.model import model_gateway as _real

_sys.modules[__name__] = _real
