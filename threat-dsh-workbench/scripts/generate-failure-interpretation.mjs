/**
 * Generate the DSH side of the failure-interpretation contract from the backend.
 *
 * WHY THIS IS GENERATED AND NOT WRITTEN: the DSH track shipped a hardcoded
 * three-token list while `src/threat_report_agent/contracts.py` defined four, so
 * a provider 402 / timeout / empty reply could only be handed to the backend as
 * UNKNOWN or as STATIC_BOUNDARY -- i.e. as a statement about the SAMPLE. A copy
 * of the token list in this repository is the defect, so this script carries no
 * tokens of its own: it reads the enum member values out of the Python source,
 * hashes that source, and writes the list, the derived union type and the hash.
 *
 * The generated file is checked in because the workbench runs without the Python
 * tree present, but `tests/model-routing-audit.test.mjs` re-reads BOTH sides and
 * fails when they are not equal as sets in both directions, so the checked-in
 * artifact cannot drift silently.
 *
 * Usage: node scripts/generate-failure-interpretation.mjs [--check]
 *   (default) rewrite the generated file
 *   --check   exit 1 when the checked-in file does not match the Python source
 */
import { createHash } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const workbench = dirname(here)
const repoRoot = dirname(workbench)

export const SOURCE_RELATIVE = 'src/threat_report_agent/contracts.py'
export const OUTPUT_RELATIVE = 'threat-dsh-workbench/packages/threat-plugin-sdk/src/failure-interpretation.generated.ts'

export const SOURCE_PATH = join(repoRoot, SOURCE_RELATIVE)
export const OUTPUT_PATH = join(repoRoot, OUTPUT_RELATIVE)

const ENUM_NAME = 'FailureInterpretation'

/**
 * Extract the member values of `class FailureInterpretation(StrEnum)`.
 *
 * Deliberately strict: only `NAME = "VALUE"` lines inside that class body, and a
 * class that yields nothing is an error rather than an empty contract -- an
 * empty generated tuple would make "the union is empty" compile.
 */
export function extractFailureInterpretation(source) {
  const lines = source.split(/\r?\n/)
  const start = lines.findIndex((line) => new RegExp(`^class ${ENUM_NAME}\\(`).test(line))
  if (start < 0) throw new Error(`${SOURCE_RELATIVE}: class ${ENUM_NAME}(...) not found`)
  const values = []
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index]
    if (/^\S/.test(line)) break // dedent: the class body ended
    if (/^\s*#/.test(line) || !line.trim()) continue
    const match = /^\s{4}([A-Z][A-Z0-9_]*)\s*=\s*"([A-Z0-9_]+)"\s*$/.exec(line)
    if (!match) continue
    if (match[1] !== match[2]) {
      throw new Error(`${SOURCE_RELATIVE}: ${ENUM_NAME}.${match[1]} must equal its own string value, saw "${match[2]}"`)
    }
    if (!values.includes(match[2])) values.push(match[2])
  }
  if (!values.length) throw new Error(`${SOURCE_RELATIVE}: ${ENUM_NAME} has no members; refusing to generate an empty contract`)
  return values
}

export function renderGenerated(values, sourceSha256) {
  const entries = values.map((value) => `  '${value}',`).join('\n')
  const members = values.map((value) => `  | '${value}'`).join('\n')
  return `/**
 * GENERATED FILE - DO NOT EDIT BY HAND.
 *
 * Generator: threat-dsh-workbench/scripts/generate-failure-interpretation.mjs
 * Source:    ${SOURCE_RELATIVE} (class ${ENUM_NAME})
 * Source SHA-256: ${sourceSha256}
 *
 * The DSH track must not keep its own copy of this vocabulary: the backend owns
 * it, and a client that guesses it files a model/transport fault as a statement
 * about the sample. Regenerate with:
 *   node threat-dsh-workbench/scripts/generate-failure-interpretation.mjs
 */

/** SHA-256 of the Python source this file was generated from. */
export const FAILURE_INTERPRETATION_SOURCE_SHA256 = '${sourceSha256}' as const

/** The backend's \`contracts.FailureInterpretation\` member values, in declaration order. */
export const FAILURE_INTERPRETATION_TOKENS = [
${entries}
] as const

/** The backend's failure-interpretation vocabulary as a union type. */
export type FailureInterpretation =
${members}

/**
 * MODEL_TRANSPORT_FAILURE is a fact about the PLATFORM (a provider 402, a
 * timeout, an empty reply), never a static boundary of the artifact. Only
 * NO_NEW_EVIDENCE and STATIC_BOUNDARY describe the sample. Derived from the
 * union above, so it cannot name a token the backend does not define.
 */
export type ModelTransportFailure = Extract<FailureInterpretation, 'MODEL_TRANSPORT_FAILURE'>
`
}

export function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

export async function build() {
  const source = await readFile(SOURCE_PATH, 'utf8')
  const values = extractFailureInterpretation(source)
  const sourceSha256 = sha256(source)
  return { values, sourceSha256, rendered: renderGenerated(values, sourceSha256) }
}

async function main() {
  const check = process.argv.includes('--check')
  const { values, sourceSha256, rendered } = await build()
  if (check) {
    const current = await readFile(OUTPUT_PATH, 'utf8').catch(() => '')
    if (current !== rendered) {
      console.error(`${relative(repoRoot, OUTPUT_PATH)} is stale; run: node ${relative(repoRoot, join(here, 'generate-failure-interpretation.mjs'))}`)
      process.exit(1)
    }
    console.log(`${OUTPUT_RELATIVE} matches ${SOURCE_RELATIVE} (${values.length} tokens, sha256 ${sourceSha256})`)
    process.exit(0)
  }
  await writeFile(OUTPUT_PATH, rendered, 'utf8')
  console.log(`wrote ${OUTPUT_RELATIVE}`)
  console.log(`tokens: ${values.join(', ')}`)
  console.log(`source sha256: ${sourceSha256}`)
}

// PowerShell invokes this via an absolute path, so compare resolved paths rather
// than string-assembling a URL (the workspace path contains a space).
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main()
}
