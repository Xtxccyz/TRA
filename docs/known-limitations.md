# Known Limitations

- Round 9 is not release-signed-off while the Docker Desktop Linux engine is
  unavailable. Compose E2E, fresh real-sample benchmarks, and failure drills
  must be rerun on a host with a working daemon. The current host log reports
  Docker Desktop's Inference manager cannot access the reparse-point socket at
  `%LOCALAPPDATA%\\Docker\\run\\dockerInference`.
- DSH is pinned to a Developer Preview upstream and must be upgraded through
  the lock and plugin contract tests.
- Backend source is locked by a manifest because this checkout has no Git
  metadata.
- Dynamic emulators are not executed; static abstract-execution predictions
  remain bounded, evidence-linked hypotheses.
- Historical tasks without a DSH trajectory are shown as
  `LEGACY_UNAVAILABLE` until backfill creates a session mapping.
- The legacy backend static UI remains as a compatibility surface. It is not
  loaded by the DSH threat-static profile and is not the supported product
  entry point.
