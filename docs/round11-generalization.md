# Round 11 Generalization and Certification

Round 11 uses separate development and certification corpora. The runtime can
read only submitted artifacts, deterministic tool output and approved static
knowledge. Gold answers, reference reports and evaluator rubrics stay under
`benchmarks/` or an external evaluator directory and are never passed to a
planner, retriever, model context, or RAG source.

The official corpus target is 20 held-out malware samples and 10 benign/control
programs, split into 15 malware + 5 benign for development and 5 malware + 5
benign for certification. A manifest records only an immutable path, SHA-256,
category, split and evaluator-owned expectations.

Results are evaluated with one primary root cause from the Round 11 taxonomy.
The release gate remains `BLOCKED` until mechanism precision/recall, unknown
calibration, traceability, benign false-positive, security, browser, restart,
concurrency, soak and independent-review checks are all backed by fresh runs.
