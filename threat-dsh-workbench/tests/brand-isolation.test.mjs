import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const read = (relative) => readFile(resolve(root, relative), 'utf8')

test('brand plugin is an out-of-tree web plugin with product-owned identity', async () => {
  const manifest = JSON.parse(await read('packages/threat-brand/package.json'))
  assert.equal(manifest.name, '@threat-dsh/brand')
  assert.equal(manifest.dsh.client.platform, 'web')
  assert.equal(manifest.exports['./client'], './client.js')

  const client = await read('packages/threat-brand/client.js')
  assert.match(client, /threat-workbench-brand-style/)
  assert.match(client, /threat-workbench-favicon/)
  assert.match(client, /threat-workbench\.brand-migration\.v3/)
  assert.doesNotMatch(client, /favicon\.svg/)
  assert.match(client, /localStorage\.key\(index\)/)
  assert.match(client, /localStorage\.removeItem\(key\)/)
  assert.match(client, /探索未至之境|\\u63a2\\u7d22\\u672a\\u81f3\\u4e4b\\u5883/)
  assert.match(client, /DeepSeek\(\?:\[\-\\s\]\+\)V4/)
  assert.match(client, /fishHitbox/)

  const bundle = await read('packages/threat-bundle/cordis.patch.yml')
  assert.match(bundle, /id: threat-brand/)
  assert.match(bundle, /name: '@threat-dsh\/brand'/)
})

test('profile contract does not use the legacy user DSH home', async () => {
  const launcher = await read('../scripts/start-dsh-threat-workbench.ps1')
  assert.match(launcher, /DSH_HOME\s*=\s*\$threatDshHome/)
  assert.match(launcher, /\.data\\dsh-threat-static/)
  assert.match(launcher, /\.threat-workbench-home-v1/)
  assert.match(launcher, /relativePath in @\('sessions', 'storages'/)
  assert.match(launcher, /Remove-Item -LiteralPath \$target -Recurse -Force/)
  assert.match(launcher, /Stop-StaleThreatDsh/)
  assert.match(launcher, /Port \$DshPort is already in use by an unrelated process/)
  assert.doesNotMatch(launcher, /Copy-Item[^\r\n]+sessions/)
  assert.doesNotMatch(launcher, /Copy-Item[^\r\n]+credentials/)
})
