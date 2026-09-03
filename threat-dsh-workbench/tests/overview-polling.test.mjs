import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))

test('Overview uses bounded status polling and loads the full projection once', async () => {
  const client = await readFile(resolve(root, 'packages/threat-ui-overview/client.js'), 'utf8')
  assert.match(client, /\/api\/v1\/tasks\/\$\{encodeURIComponent\(taskId\)\}\/status/)
  assert.match(client, /fullLoadedRef\.current/) 
  assert.doesNotMatch(client, /events\?after_seq=0&limit=200/)
  assert.doesNotMatch(client, /const value = await json\(`\/api\/v1\/workbench\/tasks/)
})

test('Report view waits for a terminal status and does not refetch the document', async () => {
  const client = await readFile(resolve(root, 'packages/threat-ui-report/client.js'), 'utf8')
  assert.match(client, /\/api\/v1\/tasks\/\$\{encodeURIComponent\(id\)\}\/status/)
  assert.match(client, /loadedRef\.current/)
  assert.match(client, /!\['SUCCEEDED', 'FAILED', 'CANCELLED'\]\.includes/)
})
