# Legacy WebUI Retirement

The package under `src/threat_report_agent/static` is a compatibility surface
for existing API tests and direct backend use. It is not the Round 9 product
entry point. Production startup documentation and Compose deployment use DSH
`threat-static` only; no production navigation links to the legacy UI.

The compatibility APIs remain until downstream clients migrate. A CI check
must fail if the legacy static mount is added to the production DSH profile.
