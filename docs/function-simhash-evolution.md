# Function SimHash Contract And Evolution

## Phase-one contract

Phase one uses the existing implementation in `simhash.py`, `fuzzy_hash.py`, and
`register_crypto_simhashes.py`. The application path exposes the same algorithm through
`threat_report_agent.function_simhash`:

- input: normalized lowercase instruction mnemonics;
- features: consecutive mnemonic 4-grams;
- feature hash: the first 64 bits of MD5 interpreted as little-endian;
- aggregation: uniform-weight Charikar SimHash;
- comparison: 64-bit Hamming distance.

Ghidra exports mnemonics without executing the sample. Each function fingerprint is persisted as
`STATIC_OBSERVED` `function_simhash` Evidence with the algorithm, feature, feature-hash, and value
fields. A fingerprint match is a similarity lead only. It cannot independently establish malware
family, authorship, capability, or attribution.

`known-functions.yaml` is the traceable local comparison library generated from the static byte
sequences in `register_crypto_simhashes.py`. Reference reports remain outside this library and the
analysis path.

## Deferred robustness work

The following work is deliberately deferred until phase-one feasibility and architecture have
been validated:

1. Add an operand-normalized semantic view for register classes, immediate-value classes, and
   relative versus absolute addresses.
2. Add a separate CFG view based on block, edge, degree, loop, and dominator features. Control-flow
   flattening must be treated as an adversarial case because it can substantially change this view.
3. Build a labeled perturbation benchmark covering compilers, optimization levels, simple
   obfuscation, packing, and function-boundary errors, then calibrate thresholds from observed
   same-source and different-source distance distributions.
4. Combine views only as separately recorded supporting observations. Do not convert a distance or
   combined score directly into a conclusive attribution.

These additions must version their algorithms and evidence independently so historical phase-one
fingerprints remain reproducible.

## Validation record

On 2026-08-11, the exact-output contract, Ghidra Evidence path, local known-function search,
standalone comparison tools, and eight-entry registration script passed. The repository gate was
88 pytest tests, Ruff check/format, compileall, wheel build/install, and Compose configuration.
