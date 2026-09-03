import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

test('launcher exposes the product preset through its isolated DSH home', async () => {
  const launcher = await readFile(new URL('../../scripts/start-dsh-threat-workbench.ps1', import.meta.url), 'utf8')
  assert.match(launcher, /\.agent-presets/)
  assert.match(launcher, /agent\.cordis\.yml/)
  assert.match(launcher, /Copy-Item[\s\S]*sourcePreset[\s\S]*agent\.cordis\.yml/)
})

test('profile keeps the user preset root discoverable', async () => {
  const patch = await readFile(new URL('../profiles/threat-static/cordis.patch.yml', import.meta.url), 'utf8')
  assert.match(patch, /default:\s*threat-static/)
  assert.doesNotMatch(patch, /includeUserRoot:\s*false/)
})

test('overview is a real upload and task projection, not a placeholder view', async () => {
  const source = await readFile(new URL('../packages/threat-ui-overview/client.js', import.meta.url), 'utf8')
  assert.match(source, /input.*multiple/)
  assert.match(source, /form\.append\('sample'/)
  assert.match(source, /\/api\/v1\/cases/)
  assert.match(source, /\/api\/v1\/workbench\/tasks/)
  assert.match(source, /archive_password/)
  assert.match(source, /threat\.workbench\.taskId/)
})

test('domain views project backend collections', async () => {
  const files = ['threat-ui-investigation', 'threat-ui-mechanisms', 'threat-ui-sample-timeline', 'threat-ui-evidence', 'threat-ui-report']
  for (const name of files) {
    const source = await readFile(new URL(`../packages/${name}/client.js`, import.meta.url), 'utf8')
    assert.match(source, /fetch\(/, `${name} must fetch backend data`)
    assert.match(source, /data-threat-view/, `${name} must register a product view`)
  }
})
