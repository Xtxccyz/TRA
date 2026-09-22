import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'

const root = new URL('..', import.meta.url)
test('profile composes the out-of-tree bundle without upstream paths', async () => {
  const profile = JSON.parse(await readFile(new URL('../profiles/threat-static/package.json', import.meta.url), 'utf8'))
  assert.deepEqual(profile.dsh.profile.bundles.slice(0, 2), ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'])
  assert.equal(profile.dsh.profile.bundles[2], '@threat-dsh/bundle-workbench')
})

test('acceptance plugin is self-contained and removable', async () => {
  const source = await readFile(new URL('../examples/threat-plugin-template/src/index.ts', import.meta.url), 'utf8')
  assert.match(source, /threat_echo_evidence_summary/)
  assert.match(source, /ctx\.tools\.register/)
  assert.doesNotMatch(source, /child_process|spawn\(|exec\(|fetch\(/)
})

test('workbench bundle declares every out-of-tree product extension', async () => {
  const source = await readFile(new URL('../packages/threat-bundle/src/index.ts', import.meta.url), 'utf8')
  for (const id of ['@threat-dsh/policy', '@threat-dsh/jobs', '@threat-dsh/ui-mechanisms', '@threat-dsh/ui-sample-timeline', '@threat-dsh/ui-evidence', '@threat-dsh/ui-report']) {
    assert.match(source, new RegExp(id))
  }
})

test('isolated home defaults advertise DeepSeek-V41-Flash as the conversation model', async () => {
  const source = await readFile(new URL('../profiles/threat-static/settings.defaults.yaml', import.meta.url), 'utf8')
  assert.match(source, /^llm-pi-ai:/m)
  assert.match(source, /id:\s*deepseek-flash/)
  assert.match(source, /name:\s*DeepSeek-V41-Flash/)
  assert.match(source, /provider:\s*deepseek/)
  assert.match(source, /model:\s*deepseek-flash/)
  assert.doesNotMatch(source, /model:\s*deepseek-v4-pro/)
})
