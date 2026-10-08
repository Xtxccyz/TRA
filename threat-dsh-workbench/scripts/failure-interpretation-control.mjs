/**
 * B00 can-fail control: prove the contract test FAILS when a contract value is disconnected.
 *
 * The card's failure criterion is "disconnecting a contract value must make a test fail", so a green test is not
 * evidence on its own: a test that cannot fail is worse than no test. This script mutates a real source file, runs the
 * real contract test, requires a NON-ZERO exit, restores the file from BYTES, and proves the restore by SHA-256.
 *
 * Every mutation is applied to one of the three surfaces the test compares:
 *   1. the Python enum in src/threat_report_agent/contracts.py   (the source of truth)
 *   2. the generated DSH contract (generated from that enum)      (the generated artifact)
 *   3. the DSH tool-provider runtime list                         (the consumer)
 * plus a self-check that the generator cannot restate a token table, and a self-check that the control itself can fail
 * (a deliberately wrong expectation must be detected).
 *
 * Nothing is left mutated: the script verifies the SHA-256 of every touched file equals the backup's before it exits,
 * and exits non-zero if any mutation unexpectedly PASSED or any restore did not come back byte-identical.
 *
 * Usage (from threat-dsh-workbench/): node scripts/failure-interpretation-control.mjs
 */
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const workbench = dirname(here)
const repoRoot = dirname(workbench)

const CONTRACTS = join(repoRoot, 'src', 'threat_report_agent', 'contracts.py')
const GENERATED = join(workbench, 'packages', 'threat-plugin-sdk', 'src', 'failure-interpretation.generated.ts')
const TOOL_PROVIDER = join(workbench, 'packages', 'threat-tool-provider', 'src', 'index.ts')
const GENERATOR = join(here, 'generate-failure-interpretation.mjs')
const CONTRACT_TEST = 'tests/model-routing-audit.test.mjs'

const sha256 = (value) => createHash('sha256').update(value, 'utf8').digest('hex')

const failures = []
const evidence = []

async function backup(path) {
  const text = await readFile(path, 'utf8')
  return { path, text, sha256: sha256(text) }
}

async function restore(backupEntry) {
  await writeFile(backupEntry.path, backupEntry.text, 'utf8')
  const current = await readFile(backupEntry.path, 'utf8')
  const digest = sha256(current)
  const ok = digest === backupEntry.sha256 && current === backupEntry.text
  evidence.push(`restore ${backupEntry.path} sha256=${digest} expected=${backupEntry.sha256} identical=${ok}`)
  if (!ok) failures.push(`restore did not come back byte-identical: ${backupEntry.path}`)
  return ok
}

/** Run one test file and return { status, output }. `status === 0` means the test PASSED. */
function runNodeTest(testFile) {
  const result = spawnSync(process.execPath, ['--test', testFile], {
    cwd: workbench,
    encoding: 'utf8',
    env: process.env,
  })
  const output = `${result.stdout || ''}${result.stderr || ''}`
  return { status: result.status, signal: result.signal, output }
}

const runContractTest = () => runNodeTest(CONTRACT_TEST)

/**
 * One mutation = write `mutated` over `file`, run `testFile`, require failure, restore, prove the digest.
 * `expectFailureMatching` is a regex the failing output must contain: an unrelated red test is not evidence.
 */
async function expectContractTestToFail(label, file, mutate, expectFailureMatching, testFile = CONTRACT_TEST) {
  const original = await backup(file)
  const mutated = mutate(original.text)
  if (mutated === original.text) {
    failures.push(`${label}: the mutation changed nothing; the control is not testing anything`)
    return
  }
  await writeFile(file, mutated, 'utf8')
  const mutatedDigest = sha256(await readFile(file, 'utf8'))
  evidence.push(`\n[${label}] mutated ${file}`)
  evidence.push(`[${label}] mutated sha256=${mutatedDigest} (was ${original.sha256})`)
  let run
  try {
    run = runNodeTest(testFile)
  } finally {
    await restore(original)
  }
  evidence.push(`[${label}] command: node --test ${testFile}`)
  evidence.push(`[${label}] exit code: ${run.status}`)
  if (run.status === 0) {
    failures.push(`${label}: the test PASSED with a contract value disconnected (exit 0)`)
    return
  }
  if (!expectFailureMatching.test(run.output)) {
    failures.push(`${label}: the test failed for an unrelated reason; output did not match ${expectFailureMatching}`)
    evidence.push(`[${label}] failing output tail:\n${run.output.split(/\r?\n/).slice(-25).join('\n')}`)
    return
  }
  const related = /missing tokens|extra tokens|must not restate|must not hardcode|one failure-interpretation contract/.test(run.output)
  evidence.push(`[${label}] failure names the contract: ${related}`)
  if (!related) failures.push(`${label}: failing output did not name a contract mismatch`)
}

/**
 * A self-check of the CONTROL itself: with a target test that can only pass, the helper must record a problem.
 * Without this, a control whose mutation never reached the file (or which ran the wrong command) would look green.
 * The self-check deliberately does NOT append to `failures`: the failure it provokes is the expected outcome, so only
 * the observation is asserted.
 */
async function selfCheckTheControlCanFail() {
  const alwaysGreen = join(workbench, 'tests', 'zz-control-selfcheck.test.mjs')
  const source = "import test from 'node:test'\ntest('always green', () => {})\n"
  await writeFile(alwaysGreen, source, 'utf8')
  const originalFailures = failures.slice()
  await expectContractTestToFail(
    'self-check: a target test that passes must be reported as a failed control',
    alwaysGreen,
    (text) => text.replace('always green', 'still green'),
    /missing tokens|extra tokens/,
    'tests/zz-control-selfcheck.test.mjs',
  )
  const provoked = failures.splice(originalFailures.length)
  const recordedFailure = provoked.length > 0
  evidence.push(`\n[self-check] a mutation whose target test still passes produced a control failure: ${recordedFailure}`)
  evidence.push(`[self-check] recorded: ${provoked.join(' | ') || '(nothing)'}`)
  if (!recordedFailure) failures.push('self-check: the control helper accepted a passing target test')
  // Delete the scratch target so the control is repeatable and leaves nothing behind. `pnpm test` globs
  // `tests/*.test.mjs`, but the self-check opts in explicitly, so removing it here changes no test count.
  await rm(alwaysGreen, { force: true })
}

const generatedBackups = {
  generated: await backup(GENERATED),
  contracts: await backup(CONTRACTS),
  provider: await backup(TOOL_PROVIDER),
}

// The baseline: the control is only meaningful if the test passes BEFORE any mutation.
const baseline = runContractTest()
evidence.push(`baseline: node --test ${CONTRACT_TEST} -> exit code ${baseline.status} (0 = green before mutation)`)
if (baseline.status !== 0) {
  failures.push(`baseline is already red (exit ${baseline.status}); the control proves nothing`)
  evidence.push(baseline.output.split(/\r?\n/).slice(-30).join('\n'))
}
evidence.push(`baseline sha256 contracts.py=${generatedBackups.contracts.sha256}`)
evidence.push(`baseline sha256 generated=${generatedBackups.generated.sha256}`)

// 1. Disconnect a token from the GENERATED DSH contract.
await expectContractTestToFail(
  '1 generated file: drop MODEL_TRANSPORT_FAILURE',
  GENERATED,
  (text) => text.replace(/^  'MODEL_TRANSPORT_FAILURE',\n/m, ''),
  /one failure-interpretation contract|missing tokens|extra tokens/,
)

// 2. Disconnect a token from the PYTHON enum (the source of truth).
await expectContractTestToFail(
  '2 contracts.py: drop MODEL_TRANSPORT_FAILURE from the enum',
  CONTRACTS,
  (text) => text.replace(/^    MODEL_TRANSPORT_FAILURE = "MODEL_TRANSPORT_FAILURE"\n/m, ''),
  /one failure-interpretation contract|missing tokens|extra tokens/,
)

// 3. Disconnect the CONSUMER: make the tool provider hardcode a copy again.
await expectContractTestToFail(
  '3 tool provider: hardcode the token list again',
  TOOL_PROVIDER,
  (text) => text.replace(
    /^const CATALOG_FAILURE_INTERPRETATION_TOKENS: readonly FailureInterpretation\[\] =\n  FAILURE_INTERPRETATION_TOKENS$/m,
    "const CATALOG_FAILURE_INTERPRETATION_TOKENS: readonly FailureInterpretation[] =\n  ['UNKNOWN', 'NO_NEW_EVIDENCE', 'STATIC_BOUNDARY']",
  ),
  /one failure-interpretation contract|missing tokens|extra tokens|must not hardcode/,
)

// 4. Disconnect the GENERATOR: make it restate a token table instead of reading the Python source.
await expectContractTestToFail(
  '4 generator: restate the token table',
  GENERATOR,
  (text) => text.replace(
    /const entries = values\.map\(\(value\) => `  '\$\{value\}',`\)\.join\('\\n'\)/,
    "const entries = ['UNKNOWN', 'NO_NEW_EVIDENCE', 'STATIC_BOUNDARY', 'MODEL_TRANSPORT_FAILURE'].map((value) => `  '${value}',`).join('\\n')",
  ),
  /must not restate|one failure-interpretation contract/,
)

// 5. Self-check: the control itself can fail.
await selfCheckTheControlCanFail()

// Final restore proof for every touched file, from the byte backups taken before any mutation.
evidence.push('\nfinal restore proof:')
for (const entry of [generatedBackups.contracts, generatedBackups.generated, generatedBackups.provider]) {
  const current = await readFile(entry.path, 'utf8')
  const digest = sha256(current)
  const identical = digest === entry.sha256 && current === entry.text
  evidence.push(`  ${entry.path}\n    sha256=${digest}\n    expected=${entry.sha256}\n    identical=${identical}`)
  if (!identical) failures.push(`final restore mismatch: ${entry.path}`)
}

// The test must be green again after every restore: a restore that "matches bytes" but leaves a stale import would be
// caught here rather than by the gate owner.
const finalRun = runContractTest()
evidence.push(`after restore: node --test ${CONTRACT_TEST} -> exit code ${finalRun.status} (0 = green again)`)
if (finalRun.status !== 0) {
  failures.push(`the contract test is still red after restore (exit ${finalRun.status})`)
  evidence.push(finalRun.output.split(/\r?\n/).slice(-30).join('\n'))
}

console.log(evidence.join('\n'))
if (failures.length) {
  console.error('\nCONTROL FAILED:')
  for (const failure of failures) console.error(` - ${failure}`)
  process.exit(1)
}
console.log('\nCONTROL PASSED: every disconnected contract value made the contract test fail, and every byte backup was restored with a matching SHA-256.')
