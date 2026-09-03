# Round 11 D:\test Development Baseline

Generated on 2026-08-29 from four additional artifacts under
`D:\test\EQGRP_Lost_in_Translation`. The runs used the running Compose
product through its HTTP intake and Temporal static-analysis path.

## Safety and isolation

- Samples were read as immutable upload inputs only.
- No sample execution, macro execution, dynamic emulator execution, or
  sample-specified network access was performed.
- Gold answers, reference reports, and evaluator labels were not supplied to
  the runtime, planner, retriever, model context, or RAG.
- Model calls used the configured `custom / ali/qwen3.7-max` gateway. The
  observable trace records planning, replanning, action authorization and
  deterministic fallback; private chain-of-thought is not stored.

## Results

| Sample | SHA-256 | Task | Lifecycle | Outcome | Analysis class | Evidence | Claims | Trace | Audit |
|---|---|---|---|---|---|---:|---:|---:|---|
| `Architouch-1.0.0.exe` | `444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc` | `e706985e-d5b7-45b9-88ea-ffb65f23b40d` | `SUCCEEDED` | `PARTIAL` | `FULL_STATIC_ANALYSIS` | 22,114 | 42 | 3,268 | valid |
| `Doublepulsar-1.3.1.exe` | `15ffbb8d382cd2ff7b0bd4c87a7c0bffd1541c2fe86865af445123bc0b770d13` | `3328578a-d3b9-4301-af2f-267882af1969` | `SUCCEEDED` | `PARTIAL` | `BOUNDED_STATIC_ANALYSIS` | 8,951 | 52 | 4,567 | valid |
| `Eternalblue-2.2.0.exe` | `85b936960fbe5100c170b777e1647ce9f0f01e3ab9742dfc23f37cb0825b30b5` | `22a7129e-40b2-4351-b202-2b86ae46bc1f` | `SUCCEEDED` | `PARTIAL` | `BOUNDED_STATIC_ANALYSIS` | 28,921 | 28 | 3,750 | valid |
| `Pcdlllauncher-2.3.1.exe` | `79a584c127ac6a5e96f02a9c5288043ceb7445de2840b608fc99b55cf86507ed` | `dfb810a6-2870-405b-8458-35927b9cfcc6` | `SUCCEEDED` | `PARTIAL` | `BOUNDED_STATIC_ANALYSIS` | 11,758 | 36 | 6,729 | valid |

Source paths:

- `D:\test\EQGRP_Lost_in_Translation\windows\touches\Architouch-1.0.0.exe`
- `D:\test\EQGRP_Lost_in_Translation\windows\payloads\Doublepulsar-1.3.1.exe`
- `D:\test\EQGRP_Lost_in_Translation\windows\specials\Eternalblue-2.2.0.exe`
- `D:\test\EQGRP_Lost_in_Translation\windows\payloads\Pcdlllauncher-2.3.1.exe`

## What this validates

The product completed four additional real PE analyses with evidence,
claims, report synthesis and immutable audit traces. The Architouch report
included the full Round 11 report sections and a static mechanism chain of
resource/decode or integrity checks, payload extraction or API resolution,
memory preparation, environment or service checks, network references and
potential process/command execution. Its task trace showed model planning and
replanning, authorized static actions, rejected unsafe/invalid actions, claim
gate decisions and report generation.

The other three samples were truthfully classified as bounded. This is an
observation of the current static boundary, not evidence that any specific
malware behavior executed or that the boundary is correct without Gold.

## Limitations

This is a development/generalization observation only. It does not establish
mechanism precision/recall, unknown calibration, benign false-positive rates,
report usefulness, browser E2E, restart/recovery, concurrency, soak, or
independent review. The EQGRP directory contains tools, libraries and control
components in addition to threat material; no file from it is labeled benign
by this baseline.

The Round 11 release gate therefore remains `BLOCKED` until an
independently-labeled 15 malware + 5 benign development split, 5 malware + 5
benign certification split, evaluator-owned Gold and the required operational
checks are supplied and passed.

## Generated reports

- [Architouch report](../reports/round11-dtest-Architouch-1.0.0-20260829.md)
- [Doublepulsar report](../reports/round11-dtest-Doublepulsar-1.3.1-20260829.md)
- [Eternalblue report](../reports/round11-dtest-Eternalblue-2.2.0-20260829.md)
- [Pcdlllauncher report](../reports/round11-dtest-Pcdlllauncher-2.3.1-20260829.md)
