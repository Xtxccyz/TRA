# W2-W4 Review Addendum

Date: 2026-08-12

This document is the ASCII corrective record for the W2-W4 implementation review. It supersedes
any older status sentence that says fuzzy similarity is write-only, that retention is internal-only,
or that the model gateway has no auditable failure path.

## Completed In Scope

- W2 input, Case, Analysis Task, Artifact, ToolRun, Evidence, Claim, Relation, Snapshot, report,
  audit chain, and content-addressed storage paths are implemented and tested.
- W3 deterministic static extraction covers Ghidra Headless integration, PE/script/document
  parsing, functions, Xrefs, CFG blocks, strings, import/export facts, and the packaged mnemonic
  4-gram Charikar SimHash contract.
- Function similarity retrieval is implemented as a bounded deterministic ToolRun. It searches the
  packaged `known-functions.yaml` catalog and same-task function Evidence, and records only
  `STATIC_OBSERVED` supporting Evidence. It never performs automatic attribution.
- W3 triage/static Agents are deterministic Evidence-to-Claim rules. This is the intentional
  offline fallback; they are not represented as a production LLM multi-agent consensus engine.
- W4 single-sample default is B0xD3. PE depth is D3 only when Ghidra and function Evidence
  succeed. High-value function ranking is connected and capped at TOP-15.
- W4 function interface/call/mechanism/IOC Evidence, script line anchors, OOXML embedded child
  Artifacts, object-tree `CONTAINS`, `DROPS`, `LOADS`, `DECRYPTS`, `EXECUTES`, and `INJECTS`
  relations, and confirmed/inferred/unknown static attack-chain reporting are implemented.
- W4 model adapter baseline supports OpenAI-compatible providers and native Anthropic Messages
  providers through explicit `api_style` configuration, primary/fallback routing, schema
  validation, timeout/failure handling, bounded Evidence context, and ModelCall persistence.
- Case archival, UTC daily audit sealing, evidence purge request/review/execute, and public API/CLI
  entry points are implemented. ContentBlob metadata remains intact when backing bytes are disposed,
  preserving historical foreign keys and provenance.
- Snapshot reads support a versioned 1.0-to-2.0 migration path. The packaged known-function
  catalog is preferred after installation.

## Review Gate

```text
python -m pytest -q                 105 passed
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m compileall -q src tests scripts
python -m py_compile simhash.py fuzzy_hash.py register_crypto_simhashes.py
docker compose config --quiet
```

No sample, script, macro, generated code, or dynamic payload was executed.

## Explicitly Deferred Beyond W4

These are not silently promoted to complete:

- OIDC/JWT adapters, production Principal/RBAC enforcement, and emergency access controls.
- Independent Audit Sealer ownership, external signing keys, Merkle/WORM storage, and disaster
  recovery.
- Dedicated encrypted/restricted model payload storage with retention and destruction policy.
- ATT&CK STIX/RAG, benchmark scoring, multi-model quality evaluation, and adversarial consensus.
- Module-level performance metrics, package replay, release hardening, and deployment certification.

The W2-W4 result is therefore a reviewable, static-only, extensible development baseline rather
than a production release claim.
