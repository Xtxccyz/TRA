# Static Derived And Inferred Are Evidence Natures

Status: Accepted

## Context

ADR-0016 established an important initial rule: an Agent conclusion must not
be represented as if it were a direct tool observation. Its original model
placed `STATIC_INFERRED` only on Claims.

The evidence-recovery investigation now has two additional kinds of static
result that must be preserved and evaluated before a Claim is accepted. An
exact, bounded evaluator can replay a decode operation or propagate a constant
without interpreting an unobserved runtime path. Conversely, a bounded
abstract interpreter can provide useful possible values while merging paths or
approximating state. Neither result is a direct observation, but both are
evidence with independently useful provenance.

## Decision

This ADR supersedes ADR-0016 for evidence-nature classification.

- `STATIC_OBSERVED` is a direct output of a read-only static tool.
- `STATIC_DERIVED` is an exact, reproducible computation over preserved static
  inputs. It records the evaluator version, input Evidence IDs, input digest,
  and output digest.
- `STATIC_INFERRED` is a bounded static interpretation, approximation, or
  path-merged result. It records its source Evidence and limiting assumptions.

`STATIC_DERIVED` and `STATIC_INFERRED` may be stored as Evidence. This does
not authorize either one as a conclusion by itself. A Claim remains a separate
assertion, links its supporting or refuting Evidence, and must pass its
applicable deterministic verifier and Claim Gate. A decompiler rendering alone
does not qualify as `STATIC_DERIVED`.

## Consequences

Reports can distinguish direct facts, reproducible static results, and
interpretive static results without overstating any of them as runtime proof.
Blind evaluations and semantic differentials can also trace a conclusion back
to the exact evaluator and immutable inputs that produced it. Existing rows
that use the old ADR-0016 vocabulary remain historical records; new producers
must follow this classification and preserve the required provenance.
