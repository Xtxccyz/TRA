import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))

test('launcher reuses an active threat-static process instead of interrupting it', async () => {
  const script = await readFile(resolve(root, '../scripts/start-dsh-threat-workbench.ps1'), 'utf8')
  assert.match(script, /Reusing running threat-static process/)
  assert.match(script, /\$dshProcess = if \(\$existingDsh\)/)
  assert.doesNotMatch(script, /Stopped stale threat-static process/)
})
