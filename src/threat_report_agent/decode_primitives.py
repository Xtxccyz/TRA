"""Compatibility shim: this module MOVED to `threat_report_agent.facts.decode_primitives.py`.

Structural move only - no behaviour change. The shim rebinds `sys.modules` to the real module instead of
`import *`, so one module object serves both paths and PRIVATE names remain reachable (45 test files use them),
and patching either path affects the other.
"""
import sys as _sys

from threat_report_agent.facts import decode_primitives as _real

_sys.modules[__name__] = _real
