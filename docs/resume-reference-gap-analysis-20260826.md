# Resume Reference Gap Analysis

## Scope and isolation

The reference report `D:\test\Resume\20260730_Resume_恶意样本分析报告.md` and its PDF rendering were
used only for post-analysis evaluation. They were not included in the submitted Artifact set,
model context, scheduler context, or evidence store. The independent baseline used only:

- `ComHost.exe.VIR` (SHA-256 `b405a781dbf24a6f6429f122b40b06c9158d78480d6bCA4C8FE5DB9D74E8F7E1`)
- `Resume.pdf                                                               .exe.VIR` (SHA-256 `6bb6bfcbe68de69077b567789D5970C6613B1D4FB89BECC4CF7A2F9A49861145`)

The 7z carrier and all report files were excluded. No sample was executed.

## Observed baseline

The deterministic parser produced PE identity, section metadata, imports, resources, strings,
basic indicators, and conservative mechanism candidates. Local Ghidra 12.1.2 completed for both
PEs (704 and 3,455 functions respectively), but the existing report path primarily exposed
function, call, CFG, and SimHash rows. The output did not reliably synthesize the mechanism chain.

## Differential findings

| Target capability | Current result | Gap | General fix |
|---|---|---|---|
| Sample inventory and hashes | Present | Low-level rows are not promoted into a concise finding | Add an evidence-backed inventory summary |
| Entry point, architecture, sections | Present | RVA/file-offset context is scattered | Preserve anchors in mechanism findings |
| Loading chain | Partial | API presence is not assembled into ordered function chains | Add ordered call-chain aggregation |
| Decryption/decoding | Partial | Encoded blobs and XOR candidates are not tied to a function or output | Add decode-chain evidence with confidence and limits |
| C2 protocol | Weak | Network APIs and decoded/embedded endpoint strings are not correlated | Add endpoint-to-call-site correlation and protocol candidate |
| Persistence and process behavior | Weak | CreateProcess/ShellExecute/registry/schtasks indicators are separate | Add behavior-chain aggregation and ATT&CK candidates |
| Anti-analysis | Partial | Environment APIs are listed but not explained as a branch hypothesis | Add grouped anti-analysis mechanism findings |
| Function review | Present | Priority claims do not carry mechanism explanation | Enrich top-function claims with call-chain rationale |
| Dynamic simulation | Not available locally | No Qiling, Speakeasy, or flare-emu dependency is installed | Add capability-detecting, bounded adapter seam; never claim simulation when unavailable |
| Report form | Partial | Modules exist but read like evidence ledger rows | Add analyst assessment rows with findings, rationale, confidence, and limitations |

## Safety findings

The sample must remain a read-only Artifact. Any future emulator adapter must be network-disabled,
filesystem-scoped, time/instruction bounded, and emit `DYNAMIC_OBSERVED` Evidence only when an
adapter actually ran. Static API presence must remain a hypothesis, not proof of execution.

## Acceptance target

For a PE with enough recoverable evidence, the report must contain at least one evidence-backed
mechanism finding for each supported dimension (loading, decode, execution/persistence, network,
anti-analysis), include function/RVA anchors when available, include conservative ATT&CK candidates,
and explicitly mark unavailable dynamic evidence. A sample without the relevant evidence must get a
negative/unknown finding rather than a fabricated chain.
