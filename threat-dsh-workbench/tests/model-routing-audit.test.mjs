/**
 * B00 audit: the real model routing and the prompt files that actually take
 * effect, pinned as an executable contract.
 *
 * The plan requires the workbench to be auditable on measured routing facts and
 * to keep model failure distinguishable from a static-analysis boundary. A
 * paragraph in a status note cannot fail when the routing drifts, so this test
 * reads the backend sources (read-only) and asserts the effective points.
 *
 * It is deliberately semantic: no line numbers, no file hashes of mutable
 * files. Renaming a prompt id, bumping a prompt version without updating its
 * call site, moving a prompt file that is never loaded, or dropping a
 * transport-failure code the workbench claims to distinguish all fail here.
 */
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'

const ROOT = new URL('../../', import.meta.url)
const read = (relative) => readFile(new URL(relative, ROOT), 'utf8')

/** Python / TS string-literal tokens, i.e. `'X'` or `"X"`. */
const quotedTokens = (text) => [...text.matchAll(/['"]([A-Z][A-Z0-9_]*)['"]/g)].map((match) => match[1])

/**
 * The values an enum/union member is ASSIGNED, i.e. the right-hand side of `NAME = "X"` or `  'X',`. Prose inside a
 * comment is not a value: the enum's own explanatory comment quotes `"FAILED"`, and reading that as a contract member
 * is exactly the kind of leak this test exists to prevent.
 */
function assignedTokens(text) {
  const found = []
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*(#|\/\/|\*|\/\*)/.test(line)) continue
    const body = line.includes('=') ? line.slice(line.indexOf('=') + 1) : line
    found.push(...quotedTokens(body))
  }
  return found
}

/** Set equality in BOTH directions: a missing token and an extra token both fail. */
function assertSameTokenSet(left, right, label) {
  const leftSet = new Set(left)
  const rightSet = new Set(right)
  assert.deepEqual(
    [...rightSet].filter((token) => !leftSet.has(token)),
    [],
    `${label}: missing tokens`,
  )
  assert.deepEqual(
    [...leftSet].filter((token) => !rightSet.has(token)),
    [],
    `${label}: extra tokens`,
  )
}

const SERVICE = 'src/threat_report_agent/service.py'
const AGENTS = 'src/threat_report_agent/model/agents.py'
const MAIN = 'src/threat_report_agent/main.py'
const GATEWAY = 'src/threat_report_agent/model/model_gateway.py'
const RUNTIME = 'src/threat_report_agent/model/agent_runtime.py'
const MANIFEST = 'src/threat_report_agent/prompts/manifest.json'
const TOOLS = 'threat-dsh-workbench/packages/threat-tool-provider/src/index.ts'
const CLASSIFIER = 'threat-dsh-workbench/packages/threat-plugin-sdk/src/model-failure.ts'

/** Every `self.prompts.require("<id>", "<version>")` in the backend. */
function requiredPrompts(source) {
  const found = []
  for (const match of source.matchAll(/prompts\.require\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)/g)) {
    found.push({ id: match[1], version: match[2] })
  }
  return found
}

test('every prompt file in the manifest is loaded at a real call site, at the manifest version', async () => {
  const manifest = JSON.parse(await read(MANIFEST))
  const service = await read(SERVICE)
  const agents = await read(AGENTS)

  const manifestPairs = new Set(manifest.prompts.map((item) => `${item.id}@${item.version}`))
  const required = requiredPrompts(service)
  assert.ok(required.length >= 4, `expected the backend to require the built-in prompts, saw ${required.length}`)
  for (const item of required) {
    assert.ok(
      manifestPairs.has(`${item.id}@${item.version}`),
      `service.py requires ${item.id}@${item.version}, which the manifest does not define`,
    )
  }

  // triage-agent and static-analysis-agent are loaded through _AgentBase, which
  // pins the version and receives the id from the concrete agent class.
  const baseVersion = /prompts\.require\(prompt_id,\s*"([^"]+)"\)/.exec(agents)
  assert.ok(baseVersion, 'model/agents.py must load its prompt through _AgentBase')
  const agentPromptIds = [...agents.matchAll(/super\(\)\.__init__\(prompts,\s*"([^"]+)"/g)].map((m) => m[1])
  assert.deepEqual(agentPromptIds.sort(), ['static-analysis-agent', 'triage-agent'])
  for (const id of agentPromptIds) {
    assert.ok(
      manifestPairs.has(`${id}@${baseVersion[1]}`),
      `_AgentBase loads ${id}@${baseVersion[1]}, which the manifest does not define`,
    )
  }

  const loadedIds = new Set([...required.map((item) => item.id), ...agentPromptIds])
  for (const item of manifest.prompts) {
    assert.ok(
      loadedIds.has(item.id),
      `${item.file} is shipped but no backend call site loads ${item.id}: prose that never takes effect`,
    )
  }
  assert.equal(manifest.schema_version, '1.0')

  // A prompt that names the wrong report route sends the model to a citation it
  // cannot make: the official revision is the one the workbench report route
  // publishes, and the workbench context carries it as official_report_revision_id.
  const staticPrompt = await read('src/threat_report_agent/prompts/static-analysis-system-v1.md')
  assert.match(staticPrompt, /GET \/api\/v1\/workbench\/tasks\/\{id\}\/report/)
  assert.match(staticPrompt, /official_report_revision_id/)
})

test('the DSH conversation route owns its own prompt and never loads a backend prompt file', async () => {
  const service = await read(SERVICE)
  const main = await read(MAIN)
  const start = service.indexOf('def workbench_model_complete')
  assert.ok(start > 0, 'workbench_model_complete must exist')
  const rest = service.slice(start + 1)
  const nextDef = rest.search(/\n    def /)
  const body = nextDef > 0 ? rest.slice(0, nextDef) : rest

  // The route is client-supplied messages: this is why editing a file under
  // src/threat_report_agent/prompts/ cannot change what the DSH chat model sees.
  assert.doesNotMatch(body, /prompts\.require/)
  assert.match(body, /messages=tuple\(messages\)/)
  assert.match(body, /prompt_sha256/)
  // The exact request is stored, so the instruction that took effect is auditable.
  assert.match(body, /request_stored = self\._store_model_payload\(/)

  assert.match(main, /class WorkbenchModelRequest[\s\S]{0,1600}prompt_id: str = Field\(min_length=1/)
  assert.match(main, /class WorkbenchModelRequest[\s\S]{0,1600}prompt_version: str = Field\(min_length=1/)
  assert.match(main, /class WorkbenchModelRequest[\s\S]{0,1600}prompt_sha256: str = Field\(min_length=64/)
  assert.match(main, /class WorkbenchModelRequest[\s\S]{0,2400}messages: list\[dict\[str, str\]\] = Field\(min_length=1/)
})

test('one failure-interpretation contract: the Python enum, the generated file and the DSH runtime list are equal SETS', async () => {
  const contracts = await read('src/threat_report_agent/contracts.py')
  const main = await read(MAIN)
  const generated = await read('threat-dsh-workbench/packages/threat-plugin-sdk/src/failure-interpretation.generated.ts')
  const sdk = await read('threat-dsh-workbench/packages/threat-plugin-sdk/src/index.ts')
  const tools = await read(TOOLS)

  // 1. The backend enum is the source of truth. `FAILURE_INTERPRETATION_TOKENS` is derived from it, and both Literal
  //    fields unpack that tuple instead of re-listing the tokens (a re-listed copy is how the DSH side came to accept
  //    three of the four tokens).
  const enumBody = /class FailureInterpretation\(StrEnum\):([\s\S]*?)\n\S/.exec(contracts)
  assert.ok(enumBody, 'contracts.py must define class FailureInterpretation(StrEnum)')
  const enumTokens = assignedTokens(enumBody[1])
  assert.ok(enumTokens.length >= 4, `expected the enum to name its tokens, saw ${enumTokens.length}`)
  assert.match(
    contracts,
    /FAILURE_INTERPRETATION_TOKENS: tuple\[str, \.\.\.\] = tuple\(member\.value for member in FailureInterpretation\)/,
    'the token tuple must be DERIVED from the enum, not written out again',
  )
  assert.match(
    contracts,
    /failure_interpretation: Literal\[\*FAILURE_INTERPRETATION_TOKENS\]/,
    'contracts.InvestigationAction.failure_interpretation must unpack the derived token tuple',
  )
  assert.match(
    main,
    /failure_interpretation: Literal\[\*FAILURE_INTERPRETATION_TOKENS\]/,
    'main.WorkbenchActionRequest.failure_interpretation must unpack the derived token tuple',
  )
  // No second copy of the list anywhere on the backend side.
  const mainTuple = /_FAILURE_INTERPRETATION_TOKENS(?:\s*:\s*[^=]+)?\s*=\s*\(([^)]*)\)/.exec(main)
  assert.equal(
    mainTuple,
    null,
    'main.py must not keep its own token tuple; import the contract constant instead',
  )
  assert.match(
    main,
    /_FAILURE_INTERPRETATION_TOKENS: tuple\[str, \.\.\.\] = FAILURE_INTERPRETATION_TOKENS/,
    'main.py must bind the contract constant, never restate the tokens',
  )

  // 2. The generated file is a GENERATED contract: it names its generator and its source and records the SHA-256 of
  //    the Python file it was derived from. The DSH track may not carry a hand-written copy of the vocabulary.
  assert.match(generated, /GENERATED FILE - DO NOT EDIT BY HAND/)
  assert.match(generated, /scripts\/generate-failure-interpretation\.mjs/)
  assert.match(generated, /src\/threat_report_agent\/contracts\.py/)
  assert.match(generated, /FAILURE_INTERPRETATION_SOURCE_SHA256 = '[0-9a-f]{64}'/)
  assert.match(generated, /export type FailureInterpretation =/)
  const generatedArray = /export const FAILURE_INTERPRETATION_TOKENS = \[([\s\S]*?)\] as const/.exec(generated)
  assert.ok(generatedArray, 'the generated file must export FAILURE_INTERPRETATION_TOKENS as a readonly tuple')
  const generatedTokens = assignedTokens(generatedArray[1])

  // 3. The generator must not carry tokens of its own: it can only produce values it read from the Python source.
  const generator = await read('threat-dsh-workbench/scripts/generate-failure-interpretation.mjs')
  assert.match(generator, /SOURCE_RELATIVE = 'src\/threat_report_agent\/contracts\.py'/)
  const generatorCode = generator
    .replace(/\/\*\*[\s\S]*?\*\//g, '') // doc blocks
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/`[^`]*`/g, '``') // template literals are the rendered TS, not a token table
  assert.deepEqual(
    [...new Set(quotedTokens(generatorCode))].filter((token) => enumTokens.includes(token)),
    [],
    'the generator must not restate a single contract token as a string; it reads them from contracts.py',
  )

  // 4. The DSH consumers use the generated contract, not their own list.
  assert.match(sdk, /from '\.\/failure-interpretation\.generated\.ts'/)
  assert.match(sdk, /readonly failure_interpretation: FailureInterpretation/)
  assert.doesNotMatch(
    sdk,
    /failure_interpretation: 'UNKNOWN' \| 'NO_NEW_EVIDENCE' \| 'STATIC_BOUNDARY'/,
    'the SDK union must be the generated one, not a hand-written three-token union',
  )
  assert.match(
    tools,
    /^const CATALOG_FAILURE_INTERPRETATION_TOKENS: readonly FailureInterpretation\[\] =\n  FAILURE_INTERPRETATION_TOKENS$/m,
    'the tool provider token list must be exactly the imported generated contract',
  )
  assert.match(
    sdk,
    /\} from '\.\/failure-interpretation\.generated\.ts'/,
    'the SDK must re-export the generated contract, not keep a list of its own',
  )
  assert.match(
    tools,
    /^import \{[\s\S]{0,600}?\bFAILURE_INTERPRETATION_TOKENS,/m,
    'the tool provider must import the generated token tuple from the SDK',
  )
  assert.doesNotMatch(
    tools,
    /\['UNKNOWN', 'NO_NEW_EVIDENCE', 'STATIC_BOUNDARY'\]/,
    'the tool provider must not hardcode the token list',
  )

  // 5. THE contract check: backend enum == generated file == DSH runtime list, as sets in both directions.
  //    The tool provider's list IS `FAILURE_INTERPRETATION_TOKENS` (asserted above by its initializer), and the SDK
  //    re-exports that identifier from the generated file, so the consumer's runtime list is the generated one by
  //    construction. The values it posts are pinned by `tests/failure-interpretation-runtime.test.ts`.
  const runtimeTokens = [...generatedTokens]
  assertSameTokenSet(generatedTokens, enumTokens, 'generated file vs contracts.FailureInterpretation')
  assertSameTokenSet(runtimeTokens, enumTokens, 'DSH runtime list vs contracts.FailureInterpretation')

  // The distinction the card exists for.
  for (const token of ['MODEL_TRANSPORT_FAILURE', 'STATIC_BOUNDARY']) {
    assert.ok(enumTokens.includes(token), `the contract must define ${token}`)
  }
})

test('backend model-failure surfaces are all named by the workbench classifier', async () => {
  const gateway = await read(GATEWAY)
  const runtime = await read(RUNTIME)
  const classifier = await read(CLASSIFIER)
  const backend = `${gateway}\n${runtime}`

  const surfaces = [
    'MODEL_CALLS_DISABLED',
    'MODEL_NOT_CONFIGURED',
    'MODEL_PROVIDERS_UNAVAILABLE',
    'REASONING_BUDGET_EXHAUSTED',
    'COMPLETION_BUDGET_EXHAUSTED',
    'ReadTimeout',
    'ConnectTimeout',
    'http_status',
  ]
  for (const token of surfaces) {
    assert.match(backend, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), `backend must still expose ${token}`)
    assert.match(
      classifier,
      new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      `the workbench classifier must name ${token}; a backend surface it does not classify is a transport fault that can read as a static boundary`,
    )
  }

  // 402 is a hard failure, not a retryable one: retrying it burns the only
  // fallback route, and the operator has to see it as a billing/quota fault.
  assert.match(gateway, /if attempt\.http_status in \{408, 425, 429\}:/)
  assert.doesNotMatch(gateway, /http_status in \{401, 402, 408, 425, 429\}/)
  assert.match(classifier, /MODEL_402_PAYMENT_REQUIRED/)
  assert.match(classifier, /MODEL_TIMEOUT/)
  assert.match(classifier, /MODEL_EMPTY_REPLY/)
  assert.match(classifier, /MODEL_401_AUTH/)

  // The DSH tool layer is where the backend result becomes something the model
  // reads, so it must classify rather than pass a bare status through, and it
  // must refuse to hand the backend a transport fault as a boundary token.
  const tools = await read(TOOLS)
  assert.match(tools, /classifyModelFailure/)
  assert.match(tools, /modelFailureFields/)
  assert.match(tools, /modelTransportFailureInProse/)
  assert.match(tools, /firstRequestInvestigationProtocol/)
})
