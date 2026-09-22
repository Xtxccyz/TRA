import assert from 'node:assert/strict'
import test from 'node:test'
import { apply, assertThreatStaticToolSet, FORBIDDEN_TOOLS } from '../packages/threat-policy/src/index.ts'

test('threat-static policy denies host execution and sample-network tools', () => {
  assert.ok(FORBIDDEN_TOOLS.includes('bash'))
  assert.ok(FORBIDDEN_TOOLS.includes('pwsh'))
  assert.ok(FORBIDDEN_TOOLS.includes('write'))
  assert.ok(FORBIDDEN_TOOLS.includes('web_fetch'))
  assert.ok(FORBIDDEN_TOOLS.includes('web_search'))
  assert.equal((FORBIDDEN_TOOLS as readonly string[]).includes('todo_write'), false)
  assert.equal((FORBIDDEN_TOOLS as readonly string[]).includes('ask_user_question'), false)
  assert.throws(() => assertThreatStaticToolSet(['read', 'bash']), /bash/)
  assert.doesNotThrow(() => assertThreatStaticToolSet(['threat_propose_static_action', 'todo_write', 'ask_user_question']))
})

test('policy guard denies forbidden tools at execution time', () => {
  const guards: Array<(execution: { name?: string }) => string | undefined> = []
  apply({
    inject: (_deps: readonly string[], callback: (scope: unknown) => unknown) => callback({
      tools: { guard: (decide: (execution: { name?: string }) => string | undefined) => guards.push(decide) },
    }),
  } as never)
  assert.equal(guards.length, 1)
  assert.match(String(guards[0]({ name: 'pwsh' })), /denies pwsh/)
  assert.match(String(guards[0]({ name: 'write' })), /denies write/)
  assert.equal(guards[0]({ name: 'todo_write' }), undefined)
  assert.equal(guards[0]({ name: 'threat_propose_static_action' }), undefined)
})
