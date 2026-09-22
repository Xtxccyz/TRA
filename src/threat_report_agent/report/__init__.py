"""Report composition package: plan section 7.3 (P2-R).

WHAT IS IN HERE - P2-R's scope is now COMPLETE, all four modules moved byte-identically behind root `sys.modules`
shims (plan step P4 deletes the shims, in its own checkpoint):

  * `analyst_report` - the official-composition surface: the compose gate, the deterministic renderer, the official
    markdown composer and the semantic-gain helpers,
  * `reporting` - the Document/evaluation layer (11,814 lines): the report document, the projections, the quality
    and analytical violation gates and the display budget,
  * `report_verification` - the verification helpers,
  * `gold_output_bar` - the gold-output bar.

WHY THERE ARE NO RE-EXPORTS HERE: plan section 3.2 says one concept may have only one canonical implementation and
that re-exporting is not a second implementation - but a re-export list is also a second IMPORT SURFACE, and the
report path already has an interface: the `ReportRevisionWriter` port in `threat_report_agent/ports.py`. Consumers
import `threat_report_agent.report.<module>` directly, or the old path, which is a `sys.modules` shim and therefore
the SAME module object.

STILL OUTSTANDING IN P2-R (deliberately NOT part of a structural move): plan 7.3 step 5 retires the tests-only
`document_to_markdown` exit inside `reporting.py`. It is measured at 9 test files / 78 references, it touches the
"one official markdown producer" rule, and it is a TEST-SURFACE BEHAVIOUR change, so it must be its own step rather
than ride along with this one.
"""

__all__: tuple[str, ...] = ()
