# ADR: Static Analysis Result Class

- **Status:** Accepted
- **Date:** 2026-08-30
- **Scope:** Round 11.1 semantic-analysis closure

## Context

The static pipeline can complete parser and report steps while recovering no
closed security mechanism. Treating a successful tool run as
`FULL_STATIC_ANALYSIS` overstates the product result and hides semantic gaps.
The product is static-only in this phase: absence of runtime evidence is not
itself a blocker.

## Decision

Result class is determined independently from task lifecycle and outcome:

### `FULL_STATIC_ANALYSIS`

All of the following are required:

1. The required artifact parser succeeds and code recovery is adequate for the
   artifact type.
2. At least one security-relevant mechanism reaches `SUPPORTED` or `VERIFIED`
   through the evidence gate, with complete semantic fields and provenance.
3. At least one semantic relation flow is available when the artifact exposes
   cross-object behavior.
4. No structural static blocker prevents analysis of the major behavior path.

Unknown details that do not block the major path are allowed. Runtime
execution, network access, or dynamic emulation are not required and remain
explicitly unobserved.

### `BOUNDED_STATIC_ANALYSIS`

Use when static analysis is useful but a structural boundary or missing
semantic closure prevents the full contract, including packed/runtime-only
code, unavailable required components, architecture/tool incompatibility,
unresolved critical imports/ordinals, severe obfuscation, or zero verified
mechanisms and relation flow after the bounded investigation budget.

### `FAILED_ANALYSIS`

Use when the artifact should be supported but the product or tool pipeline
fails to produce a successful required analysis run.

### `UNSUPPORTED_ARTIFACT`

Use for formats outside the supported artifact matrix.

## Consequences

The API and report must show pipeline completion separately from semantic
coverage. A completed parser/report pipeline can therefore be `BOUNDED`.
Reports must expose missing fields, evidence links, and static boundaries;
they must not convert navigation records, API presence, or runtime claims into
core findings.

