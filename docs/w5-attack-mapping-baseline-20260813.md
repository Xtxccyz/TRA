# W5 ATT&CK Candidate Mapping Baseline

Date: 2026-08-13

## Scope

This slice adds a bounded W5 baseline: a packaged, versioned ATT&CK snapshot and deterministic candidate mappings from structured Behavior Claims to techniques. It is not a full STIX/RAG implementation and does not call external ATT&CK APIs.

## Implementation

- `knowledge/attack-snapshot.yaml` ships with the package and records the snapshot version, technique IDs, names, descriptions, applicable modules, atomic actions, and permitted Evidence kinds.
- `attack_mapping.py` hashes the raw snapshot bytes with SHA-256. Mapping requires a structured Claim, ClaimEvidence links, and Evidence belonging to the current Task. An isolated API or string hit cannot produce a mapping.
- Every successful analysis with at least one mappable behavior creates an `attack-mapping-index` ToolRun containing snapshot version/hash, input Claim IDs, mapping count, and supporting Evidence IDs. Tasks without a structured behavior candidate do not create an empty index run.
- Results are stored in `Claim.attack_mapping` with `status: candidate`, technique details, reason, purpose, confidence, Evidence IDs, snapshot version, and hash. They are supporting evidence only and cannot establish attribution or a conclusive finding.
- The `behavior_attack` report module exposes the reason, version, and evidence chain from the Analysis Snapshot. Reference reports remain isolated and never enter Agent, mapper, or RAG context.

## Acceptance

Tests cover packaged snapshot loading and hashing, structured behavior mapping, rejection of API-only/string-only inputs, cross-Task Evidence rejection, persisted ToolRun output, and report visibility.

## Follow-up

The stable interface can later accept STIX imports, Technique/Sub-technique lifecycle data, mapping benchmarks, and PostgreSQL projection indexes. W6 remains the benchmark and serial adversarial-consensus phase; W7 remains authentication, WORM/Merkle sealing, disaster recovery, and release hardening.
