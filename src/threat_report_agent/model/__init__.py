"""Model package: plan section 7.4 (P2-M).

WHAT IS IN HERE: `model_gateway`, `agent_runtime`, `agents` and `prompts`, moved one module at a time with a root
`sys.modules` shim left behind for each (plan step P4 deletes the shims, in its own checkpoint).

WHY THERE ARE NO RE-EXPORTS AND NO FACADE: plan 3.2 allows a re-export but a re-export list is also a second
import surface, and `model` is not the name of any module, so nothing is shadowed and every moved module keeps an
effective root shim. MEASURED in the P2-M inventory: none of these four modules sits in a module-level import
cycle, so a shim cannot re-enter a half-initialised module - the failure mode that stopped the P2-V attempt.

BOUNDARY (plan 7.4 success criterion): this package returns structured planning/action proposals only. It does not
mutate the investigation graph, the Case scope, the budget or tool permissions, and the truncation and limitation
fields are identical to the pre-move baseline (frozen by the P0.5 probe).

MEASURED COLLISION, PINNED BY THE CONTRACT TEST: the package root still carries a `prompts/` DATA directory, so
`threat_report_agent.prompts` had to keep resolving to the moved `model/prompts.py` module and NOT to that
directory as a namespace package - `__path__` is absent on the resolved module, and
`resources.files("threat_report_agent")` still reaches the prompt `.md` files.

NO MODULE IS REFUSED FOR THIS PACKAGE: unlike `emulation/` (plan 7.8), none of the four locates a resource
relative to `__file__`, so the plan's own refusal rule does not apply to any of them.
"""

__all__: tuple[str, ...] = ()
