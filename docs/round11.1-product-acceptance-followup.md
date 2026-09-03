# Product Acceptance Follow-up Plan

Round 11.1 is a passing static semantic-closure release candidate. It is not
the final product certification because the following acceptance inputs and
operational proofs are still absent.

## Blocking work

1. **Evaluator corpus and Gold**: provide 20 malware and 10 benign artifacts,
   held-out partitions, expected mechanisms/IOCs/ATT&CK mappings, and an
   evaluator-owned Gold set. Run false-positive, recall, mechanism-closure,
   and report-quality metrics without exposing Gold to the runtime.
2. **Browser E2E**: exercise the supported DSH `threat-static` profile from
   upload through report export, including batch uploads, password-gated
   archives, reconnect cursors, and evidence traceability.
3. **Operational resilience**: run restart/recovery, PostgreSQL/MinIO/Temporal
   outage recovery, concurrency, and 24-hour soak tests. Preserve all audit
   and report artifacts from those runs.
4. **Independent analyst review**: have a reviewer who did not author the
   rules score the held-out reports for semantic correctness, useful HOW,
   behavior-flow reconstruction, IOC/hunting value, and calibrated unknowns.
5. **Deployment hardening**: replace development secrets, enforce Temporal
   worker isolation in production, verify independent audit-sealer credentials,
   and rerun the static-boundary/security guards on the release image.

## Exit criteria

The product may be called production-ready only when all five workstreams are
complete, the evaluator metrics meet their agreed thresholds, all safety and
recovery checks pass, and the independent review is approved. Until then the
accurate status is:

```text
Round 11.1 semantic closure: PASS
Static mechanism-analysis release candidate: ACCEPTABLE
Round 11 external certification: BLOCKED
Final product certification: NOT YET ACCEPTED
```

