# W4 Analysis Capability Correction

Date: 2026-08-23

## Finding

The first live smoke path could return `SUCCEEDED/COMPLETE` with Evidence but
no Claim for a benign script such as `import socket`. That was a real analysis
gap: parsers had extracted fragments, but the deterministic Agent did not
promote script imports and calls into behavioral reasoning.

## Correction

- The HTTP endpoint now accepts one or more `sample` parts. Multiple uploads
  are packaged as an uncompressed ZIP, then pass through the existing bounded
  intake path. The root batch Artifact, child Artifacts, ToolRuns, Evidence,
  Claims, Relations, snapshot, and report all remain in one trace.
- The static Agent promotes script imports/calls into conservative inferred
  Claims for network communication, decoding/decryption, process execution,
  and dynamic loading. Each Claim cites line-anchored Evidence.
- If a non-container file has no behavior-specific indicator, the service
  emits a `static_triage` profile Claim stating that the file was analyzed and
  no current rule matched. This is explicitly not a benign verdict.
- Existing PE/Ghidra behavior aggregation remains function-level and includes
  call names, RVA/entry anchors, Xref/CFG Evidence, priority Claims, and
  inferred component relations when extracted children exist.

## Verification

Regression tests cover the public multi-file upload endpoint and script call
promotion. The full local suite now has 146 tests passing, plus Ruff,
compileall, JavaScript syntax, and Compose validation. The live acceptance
probe remains the final check after the API image is rebuilt.

## Boundary

This is static analysis. A `STATIC_INFERRED` Claim means that the observed
imports, calls, strings, function references, or structure are consistent with
the stated behavior; it does not prove runtime execution, intent, attribution,
or C2 use. Model enrichment remains optional and auditable.
