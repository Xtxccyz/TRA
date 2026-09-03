import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))

test('resource views refresh from the shared session event stream instead of timers', async () => {
  const views = ['threat-ui-overview', 'threat-ui-investigation', 'threat-ui-mechanisms', 'threat-ui-sample-timeline', 'threat-ui-evidence', 'threat-ui-report']
  for (const view of views) {
    const source = await readFile(resolve(root, 'packages', view, 'client.js'), 'utf8')
    assert.doesNotMatch(source, /setInterval\s*\(/, `${view} must not own a polling timer`)
    assert.match(source, /onEvent/, `${view} must subscribe to session events`)
  }
})

test('context store uses the bounded session wait protocol', async () => {
  const source = await readFile(resolve(root, 'packages/threat-context-store/client.js'), 'utf8')
  assert.ok(source.includes('/analysis/wait'))
  assert.match(source, /onEvent/)
  assert.doesNotMatch(source, /setInterval\s*\(/)
})

test('Evidence uses the session-bound query endpoint without a task id body', async () => {
  const source = await readFile(resolve(root, 'packages/threat-ui-evidence/client.js'), 'utf8')
  assert.ok(source.includes('/workbench/sessions/'))
  assert.ok(source.includes('/evidence/query'))
  assert.doesNotMatch(source, /body:\s*JSON\.stringify\(\{\s*task_id/)
})

test('API client evidence helper is session-bound', async () => {
  const source = await readFile(resolve(root, 'packages/threat-api-client/src/index.ts'), 'utf8')
  const method = source.slice(source.indexOf('currentEvidence('), source.indexOf('bindAnalysis('))
  assert.ok(method.includes('/workbench/sessions/${encodeURIComponent(sessionId)}/evidence/query'))
  assert.doesNotMatch(method, /task_id/)
})
