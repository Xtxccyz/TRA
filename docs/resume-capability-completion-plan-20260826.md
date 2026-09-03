# Resume Capability Completion Plan

## Vertical slices

1. **Mechanism-chain evidence (W1)**
   - Extend the Ghidra/static aggregation seam to correlate ordered per-function calls,
     imported symbols, strings, and instruction patterns.
   - Emit `mechanism_chain` Evidence with module, function entry/RVA, ordered steps, observed
     indicators, rationale, confidence, and explicit static-only limitations.
   - Add behavior-level tests for network loader, decode, execution/persistence, and
     anti-analysis chains, plus a negative test for isolated API presence.

2. **Analyst assessment and report rendering (W2)**
   - Promote mechanism-chain Evidence to atomic Claims with evidence links.
   - Render findings before raw evidence, grouped by mechanism dimension, with ATT&CK candidates,
     confidence, and limitations.
   - Add report assertions that no section is only a field dump when mechanism evidence exists.

3. **Controlled simulation seam (W3)**
   - Add capability detection and adapters for optional flare-emu, Qiling, and Speakeasy.
   - Schedule simulation only after static triage and only through an explicit bounded policy.
   - If no adapter is installed, persist a capability/limitation Evidence row; never emulate or
     claim dynamic observations.

4. **Resume end-to-end acceptance (W4)**
   - Run the two PE files through the real service with Ghidra enabled and reference isolation.
   - Assert mechanism findings, evidence anchors, ATT&CK candidates, audit integrity, and absence
     of private model chain-of-thought or sample execution events.

## Safety and non-goals

- No sample execution, macro execution, shell invocation, or network access.
- The reference report remains evaluation-only.
- The implementation generalizes evidence patterns; it does not hard-code the Resume IP,
  filenames, or report text.
- Dynamic emulation is optional and bounded; unsupported environments remain an honest partial result.

## Review gate

The work is complete only when focused tests, the full suite, lint/compile checks, and a real Resume
run all pass. The final review must verify each target capability against this plan and report any
residual limitations explicitly.
