import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const views = ['threat-ui-investigation', 'threat-ui-mechanisms', 'threat-ui-sample-timeline', 'threat-ui-evidence', 'threat-ui-report']

test('all workbench views resolve task through the active DSH session', async () => {
  for (const view of views) {
    const source = await readFile(resolve(root, 'packages', view, 'client.js'), 'utf8')
    assert.match(source, /workbench\/sessions/)
    assert.match(source, /sessionId/)
    assert.doesNotMatch(source, /localStorage\.getItem\('threat\.workbench\.taskId'\)/)
  }
})
