import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))

test('Overview scopes task selection to the active DSH session', async () => {
  const client = await readFile(resolve(root, 'packages/threat-ui-overview/client.js'), 'utf8')
  assert.match(client, /threat\.workbench\.taskId:/)
  assert.match(client, /dsh\.sessions\.current/)
  assert.match(client, /sessionId/)
  assert.match(client, /providedSessionId/)
  assert.match(client, /const owner = runtimeSessionId/)
  assert.match(client, /dsh_session_id: owner/)
  assert.match(client, /sessionIdRef\.current !== sessionId/)
  assert.doesNotMatch(client, /localStorage\.getItem\('threat\.workbench\.taskId'\)/)
})
