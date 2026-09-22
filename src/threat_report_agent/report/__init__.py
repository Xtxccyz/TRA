"""Report composition package: plan section 7.3 (P2-R).

WHAT IS IN HERE: `analyst_report.py`, the official-composition surface - the compose gate, the deterministic
renderer, the official markdown composer and the semantic-gain helpers.

WHAT IS NOT IN HERE YET: `reporting.py`, `report_verification.py` and `gold_output_bar.py` are still at the package
root. P2-R's scope names them; this step moved only the composition module, because plan section 7.1 says to move
ONE implementation at a time and verify it before the next.

WHY THERE ARE NO RE-EXPORTS HERE: plan section 3.2 says one concept may have only one canonical implementation and
that re-exporting is not a second implementation - but a re-export list is also a second IMPORT SURFACE, and the
report path already has an interface: the `ReportRevisionWriter` port in `threat_report_agent/ports.py`. Consumers
import `threat_report_agent.report.analyst_report` directly, or the old path, which is a `sys.modules` shim and
therefore the SAME module object.
"""

__all__: tuple[str, ...] = ()
