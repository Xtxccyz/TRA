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
  // The action contract accepts exactly three tokens, so a transport fault the
  // DSH side hands over as STATIC_BOUNDARY is stored as a static boundary.
  assert.match(main, /failure_interpretation: Literal\["UNKNOWN", "NO_NEW_EVIDENCE", "STATIC_BOUNDARY"\]/)
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
