import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

test('Evidence view normalizes object anchors before rendering', async () => {
  const source = await readFile(new URL('../packages/threat-ui-evidence/client.js', import.meta.url), 'utf8')
  assert.match(source, /const displayValue = \(value\) =>/)
  assert.match(source, /JSON\.stringify\(value, null, 2\)/)
  assert.match(source, /displayValue\(item\.summary \?\? item\.anchor \?\? item\.statement \?\? item\)/)
})
